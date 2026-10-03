FROM mitmproxy/mitmproxy:11.1.3

USER root
COPY logger.py tripwire_match.py /addon/
RUN mkdir -p /registry && chown mitmproxy:mitmproxy /registry

# connection_strategy=lazy: there is no route out, and the default (eager) tries to open
# the real upstream connection first, which fails before the request can be inspected.
CMD ["mitmdump", "--listen-host", "0.0.0.0", "--listen-port", "8080", "--set", "connection_strategy=lazy", "-s", "/addon/logger.py"]
