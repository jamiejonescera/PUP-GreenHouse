FROM public.ecr.aws/lambda/python:3.9-x86_64

# Copy requirements file
COPY requirements.txt ./

# Install Python dependencies
RUN pip install -r requirements.txt

# Copy function code
COPY main.py ./

CMD ["main.handler"]