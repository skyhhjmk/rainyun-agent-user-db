FROM maven:3.9.11-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .
RUN ./mvnw -B -DskipTests dependency:go-offline
COPY src src
RUN ./mvnw -B -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /deployments
COPY --from=build /workspace/target/quarkus-app/lib/ lib/
COPY --from=build /workspace/target/quarkus-app/*.jar .
COPY --from=build /workspace/target/quarkus-app/app/ app/
COPY --from=build /workspace/target/quarkus-app/quarkus/ quarkus/
EXPOSE 8080
USER 10001
ENTRYPOINT ["java", "-Dquarkus.profile=prod", "-jar", "quarkus-run.jar"]
