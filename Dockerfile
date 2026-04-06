FROM python:3.8.10-slim

WORKDIR /code
RUN groupadd app && useradd -g app app && chown -R app:app /code

COPY . /code
WORKDIR /code/AzureFunction
RUN pip install -r requirements.txt

USER app

CMD ["python", "Datalake2Sentinel/run_local.py"]