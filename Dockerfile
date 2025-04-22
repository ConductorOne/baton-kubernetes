FROM gcr.io/distroless/static-debian11:nonroot
ENTRYPOINT ["/baton-kubernetes"]
COPY baton-kubernetes /