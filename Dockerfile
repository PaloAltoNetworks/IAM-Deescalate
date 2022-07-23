# FROM python:3-slim as builder

FROM python:3.8-slim as builder

LABEL maintainer="Jay Chen <jaychen@paloaltonetworks.com>"

RUN apt-get update && apt-get install git -y && mkdir /app

WORKDIR /app

RUN git clone https://github.com/nccgroup/PMapper.git

COPY ./ ./IAM-Deescalate

RUN cp IAM-Deescalate/misc/gathering.py PMapper/principalmapper/graphing/gathering.py

RUN cp IAM-Deescalate/misc/case_insensitive_dict.py PMapper/principalmapper/util/case_insensitive_dict.py

WORKDIR /app/IAM-Deescalate

RUN pip3 --disable-pip-version-check install -r requirements.txt


FROM gcr.io/distroless/python3

COPY --from=builder /app /app

COPY --from=builder /usr/local/lib/python3.8 /usr/local/lib/python3.8

ENV PYTHONPATH=/usr/local/lib/python3.8/site-packages

ENV AWS_SHARED_CREDENTIALS_FILE=/.aws/credentials

WORKDIR /app/IAM-Deescalate

VOLUME [ "/app/IAM-Deescalate/output/" ]

ENTRYPOINT [ "python3", "iam_desc.py" ]

CMD ["-h"]