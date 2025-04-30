# Use the official MySQL image from Docker Hub as the base image
FROM mysql:8.0

# Set environment variables for MySQL configuration
# These define the root password and a user with credentials
ENV MYSQL_ROOT_PASSWORD=password
ENV MYSQL_DATABASE=mydb
ENV MYSQL_USER=admin
ENV MYSQL_PASSWORD=password

# Expose the default MySQL port (optional, for clarity)
EXPOSE 3306

# Copy custom MySQL configuration file (optional, if you need specific settings)
# COPY my.cnf /etc/mysql/my.cnf

# The default command to run MySQL is already set in the base image
# CMD ["mysqld"]