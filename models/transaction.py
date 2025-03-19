from app import db
from sqlalchemy.orm import relationship
from sqlalchemy import func

class Transaction(db.Model):
    __tablename__ = 'transaction'

    id = db.Column("pk_transaction", db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    type = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.pk_category'), nullable=False)
    user_id = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())

    category = relationship('Category')