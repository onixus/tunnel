FROM adguard/adguardhome@sha256:aba9e3bf0613be3ba3755e1fc311b126e2c24bec25e18b6483894a88283074f0
USER root
# Upstream file capabilities conflict with an empty capability bounding set.
# Docker's namespaced unprivileged-port sysctl allows port 53 without capabilities.
RUN setcap -r /opt/adguardhome/AdGuardHome
USER 10001:10001
