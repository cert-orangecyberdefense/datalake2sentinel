FROM python:3.8.10-slim

WORKDIR /code

COPY . /code

RUN groupadd app && useradd -g app app
RUN chown -R app:app /code
RUN pip install -r requirements.txt

USER app

CMD ["python", "core.py"]