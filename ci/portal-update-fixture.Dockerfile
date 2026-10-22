# Disposable old-UI sidecar for exercising the real additive image builder.
ARG TEST_IMAGE
FROM ${TEST_IMAGE}
COPY server/upstream/app /app/app
COPY server/console /console
COPY .acceptance-bin/debug/rtrust-codec /usr/local/bin/rtrust-codec
# Leave backend modules intact, but force the candidate to replace every UI file.
RUN rm -rf /console/templates /console/static && \
    mkdir -p /console/templates /console/static && \
    printf 'legacy console template' > /console/templates/index.html && \
    printf 'legacy console style' > /console/static/console.css
WORKDIR /app
