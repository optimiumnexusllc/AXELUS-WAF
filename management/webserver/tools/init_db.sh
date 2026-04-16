docker rm -f mgt-postgres-dev

#docker run -it -d -e POSTGRES_DB=axelus -e POSTGRES_USER=axelus -e POSTGRES_PASSWORD=axelus -p 127.0.0.1:5432:5432 --name mgt-postgres-dev optimiumnexus.com/library/postgres:15.2
docker run -it -d -e POSTGRES_DB=axelus -e POSTGRES_USER=axelus -e POSTGRES_PASSWORD=axelus -p 127.0.0.1:5432:5432 --name mgt-postgres-dev postgres:15.2