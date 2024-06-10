FROM freeradius/freeradius-server:latest
COPY docker/freeradius/raddb/ /etc/raddb/
EXPOSE 1812

CMD ["radiusd", "-X"]