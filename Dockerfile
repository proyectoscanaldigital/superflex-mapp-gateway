FROM harbor.eks.glic-solutions.com/glic/zulu-openjdk-alpine:11-jre
ARG DEPENDENCY=target/dependency
COPY ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY ${DEPENDENCY}/META-INF /app/META-INF
COPY ${DEPENDENCY}/BOOT-INF/classes /app
ENV _JAVA_OPTIONS "-Xmx512m -Xms256m -XX:+UseContainerSupport -Djava.security.egd=file:/dev/./urandom  -Xverify:none -Djava.awt.headless=true  -Dfile.encoding=UTF-8 -Dspring.backgroundpreinitializer.ignore=true -Dspring.jmx.enabled=false"
ENTRYPOINT ["java","-cp","app:app/lib/*","com.glic.mappgateway.SuperflexMappGatewayApplication"]
