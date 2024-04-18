FROM ubuntu:latest
LABEL authors="igornesrallaribeiro"
COPY target/encryptapp.jar /app/encryptapp.jar
WORKDIR /app

# Comando para executar o aplicativo Spring Boot quando o contêiner for iniciado
CMD ["java", "-jar", "encryptapp.jar"]
ENTRYPOINT ["top", "-b"]