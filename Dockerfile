# Usa a versão mais recente do Python
FROM python:3.12-slim

# Define o diretório de trabalho
WORKDIR /app

# Copia apenas o arquivo de dependências primeiro para otimizar o cache do Docker
COPY requirements.txt .

# Instala as dependências de forma eficiente
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante do código para dentro do container
COPY . .

# Expõe a porta que o app usará
EXPOSE 5000

# Comando para rodar a aplicação
CMD ["python", "run.py"]