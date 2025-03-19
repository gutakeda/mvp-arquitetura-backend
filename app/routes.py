import json
import os
import base64
from functools import wraps

import requests
import jwt
from jwt.algorithms import Algorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pydantic import ValidationError
from flask import jsonify, request
from flask_openapi3 import APIBlueprint
from flasgger import swag_from

from app import db
from models.category import Category
from models.transaction import Transaction
from schemas.category import CategoryViewSchema, CategoriesListResponse
from schemas.transaction import TransactionSchema, TransactionListResponse, TransactionDelSchema


api = APIBlueprint('api', __name__, url_prefix='/api')

def get_token_auth_header():
    """Obtém o token JWT do cabeçalho Authorization."""
    auth = request.headers.get("Authorization", None)
    if not auth:
        return jsonify({"error": "Authorization header is missing"}), 401

    parts = auth.split()
    if parts[0].lower() != "bearer" or len(parts) != 2:
        return jsonify({"error": "Authorization header must be Bearer token"}), 401

    return parts[1]

def base64url_to_base64(base64url):
    """Converte base64url para base64, incluindo o padding correto."""
    padding = "=" * (4 - (len(base64url) % 4))  # Adiciona o padding necessário
    return base64.urlsafe_b64decode(base64url + padding)

def get_rsa_key_from_jwks(token):
    """Obtém a chave RSA pública para verificar a assinatura do JWT"""
    header = jwt.get_unverified_header(token)
    if header is None or "kid" not in header:
        raise ValueError("Token header missing 'kid'")

    kid = header["kid"]
    jwks_url = f"https://{os.getenv('AUTH0_DOMAIN')}/.well-known/jwks.json"
    jwks = requests.get(jwks_url).json()

    rsa_key = None
    for key in jwks["keys"]:
        if key["kid"] == kid:
            # Converte 'n' (módulo) e 'e' (expoente) de base64url para base64
            n = base64url_to_base64(key["n"])  # Converte 'n'
            e = base64url_to_base64(key["e"])  # Converte 'e'

            # Gera a chave RSA usando o módulo 'n' e o expoente 'e'
            rsa_key = rsa.RSAPublicNumbers(
                n=int.from_bytes(n, byteorder='big'),
                e=int.from_bytes(e, byteorder='big')
            ).public_key()

            break

    if not rsa_key:
        raise ValueError("Unable to find appropriate key")

    return rsa_key

def verify_jwt(f):
    """Decorator para validar JWT do Auth0."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        try:
            # Obtém a chave pública RSA do JWKS
            rsa_key = get_rsa_key_from_jwks(token)

            # Decodifica o token JWT com a chave pública RSA
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=[os.getenv('ALGORITHMS', 'RS256')],
                audience=os.getenv('API_AUDIENCE'),
                issuer=f"https://{os.getenv('AUTH0_DOMAIN')}/"
            )

            # Associa o payload ao request para o uso no endpoint
            request.user = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.JWTClaimsError:
            return jsonify({"error": "Invalid claims, please check the audience and issuer"}), 401
        except Exception as e:
            return jsonify({"error": str(e)}), 401
    return decorated

@api.get('/transactions', responses={"200": TransactionListResponse})
@verify_jwt
def list_transactions():
    """
    List transactions.

    This endpoint retrieves all transactions, ordered by creation date.

    ---
    tags:
        - Transaction
    security:
      - BearerAuth: []  # Especifica que o Bearer token é necessário
    parameters:
      - name: order_by
        in: query
        required: false
        description: Order transactions by 'asc' or 'desc'
        schema:
          type: string
    responses:
      200:
        description: A list of transactions
        content:
          application/json:
            schema: TransactionListResponse
      400:
        description: Invalid order_by parameter
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
      500:
        description: Internal server error
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
    """
    try:
        # Obter o id do usuário autenticado
        user_id = request.user.get('sub')
        print(user_id)

        # Order by 'asc' if param is not provided
        order_by = request.args.get('order_by', 'asc')

        if order_by == 'asc':
            order_clause = Transaction.created_at.asc()
        elif order_by == 'desc':
            order_clause = Transaction.created_at.desc()
        else:
            return jsonify({'error': 'Invalid order_by parameter. Use "asc" or "desc".'}), 400

        transactions = Transaction.query.filter_by(user_id=user_id).order_by(order_clause).all()

        transactions_list = [
            {
                'id': transaction.id,
                'title': transaction.title,
                'type': transaction.type,
                'amount': float(transaction.amount),
                'category_id': transaction.category_id,
                'created_at': transaction.created_at,
                'category': transaction.category.name,
            } for transaction in transactions
        ]

        return jsonify(transactions_list), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.post('/transaction', responses={"200": TransactionSchema})
@verify_jwt
@swag_from({
    'security': [
        {
            'BearerAuth': []
        }
    ],
    'summary': 'Creates transaction.',
    'description': 'This endpoint creates a new transcation.',
    'tags': ['Transaction'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'title': {
                        'type': 'string',
                        'description': 'Title of the transaction',
                        'example': 'Grocery shopping'
                    },
                    'type': {
                        'type': 'string',
                        'description': 'Type of the transaction (\'withdraw\' or \'deposit\')',
                        'example': 'withdraw'
                    },
                    'amount': {
                        'type': 'number',
                        'format': 'decimal',
                        'description': 'Amount of the transaction',
                        'example': 50.75
                    },
                    'category_id': {
                        'type': 'integer',
                        'description': 'ID of the category',
                        'example': 1
                    }
                },
                'required': ['title', 'type', 'amount', 'category_id']
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Transaction created successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string'
                    }
                }
            }
        },
        '400': {
            'description': 'Validation error',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string'
                    }
                }
            }
        },
        '500': {
            'description': 'Internal server error',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string'
                    }
                }
            }
        }
    }
})
def create_transaction():
    data = request.get_json()
    try:
         # Adiciona o user_id ao corpo da transação
        user_id = request.user.get('sub')  # Supondo que o 'sub' no JWT seja o ID do usuário
        # Validate through TransactionSchema
        transaction_data = TransactionSchema(**data)
        transaction = Transaction(
            **transaction_data.model_dump(),
            user_id=user_id  # Associa o usuário à transação
        )
        db.session.add(transaction)
        db.session.commit()
        return jsonify({"message": "Transaction added successfully"}), 200

    except ValidationError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api.delete('/transaction/<int:transaction_id>', responses={200: TransactionDelSchema})
@verify_jwt
def delete_transaction(path: TransactionDelSchema):
    """
    Delete a transaction.

    This endpoint deletes a transaction specified by its ID.

    ---
    tags:
        - Transaction
    security:
        - BearerAuth: []  # Especifica que o Bearer token é necessário
    parameters:
      - name: transaction_id
        in: path
        required: true
        description: ID of the transaction to be deleted
        schema:
          type: integer
    responses:
      200:
        description: Transaction successfully deleted
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
      404:
        description: Transaction not found
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
      500:
        description: Internal server error
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
    """
    try:
        transaction_id = path.transaction_id
        transaction = Transaction.query.get(transaction_id)
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404

        db.session.delete(transaction)
        db.session.commit()
        return jsonify({'message': 'Transaction successfully deleted'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.get('/categories', responses={"200": CategoriesListResponse})
def list_categories():
    """
    List categories with total amounts.

    This endpoint retrieves all categories and calculates the total amount for each category.

    ---
    tags:
        - Category
    responses:
      200:
        description: A list of categories with total amounts
        content:
          application/json:
            schema: CategoriesListResponse
      500:
        description: Internal server error
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
    """
    try:
        categories = Category.query.all()
        categories_list = []

        for category in categories:
            # Calculate total amount for each category
            transactions = Transaction.query.filter_by(category_id=category.id).all()
            total_amount = 0
            for transaction in transactions:
                if transaction.type == 'withdraw':
                    total_amount -= transaction.amount
                elif transaction.type == 'deposit':
                    total_amount += transaction.amount

            category_data = {
                'id': category.id,
                'name': category.name,
                'total_amount': total_amount
            }
            categories_list.append(category_data)
        return jsonify(categories_list), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.post('/category', responses={"200": CategoryViewSchema})
@swag_from({
    'summary': 'Creates category.',
    'description': 'This endpoint creates a new category.',
    'tags': ['Category'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'name': {
                        'type': 'string',
                        'description': 'Name of the category',
                        'example': 'Food'
                    }
                },
                'required': ['name']
            }
        }
    ],
    'responses': {
        '200': {
            'description': 'Category created successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string'
                    }
                }
            }
        },
        '400': {
            'description': 'Missing name parameter',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string'
                    }
                }
            }
        },
        '500': {
            'description': 'Internal server error',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string'
                    }
                }
            }
        }
    }
})
def create_category():
    data = request.get_json()

    if 'name' not in data:
        return jsonify({'error': 'Missing name parameter'}), 400

    name = data['name']
    new_category = Category(name=name)

    try:
        db.session.add(new_category)
        db.session.commit()
        return jsonify({'message': 'Category created successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500