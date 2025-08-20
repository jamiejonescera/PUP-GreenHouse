FROM public.ecr.aws/lambda/python:3.9-x86_64

# Copy requirements file
COPY requirements.txt ${LAMBDA_TASK_ROOT}

# Install Python dependencies
RUN pip install -r requirements.txt

# Copy ALL your application files to Lambda task root
COPY main.py ${LAMBDA_TASK_ROOT}
COPY admin_auth.py ${LAMBDA_TASK_ROOT}
COPY .env ${LAMBDA_TASK_ROOT}
COPY eco_pantry_config.json ${LAMBDA_TASK_ROOT}
COPY setup_aws.py ${LAMBDA_TASK_ROOT}

# Set the Lambda handler
CMD ["main.handler"]