#!/usr/bin/env bash
mvn install:install-file -Dfile=src/main/resources/dockfx-0.1-SNAPSHOT.jar -DgroupId=org.dockfx -DartifactId=dockfx -Dversion=0.1-SNAPSHOT -Dpackaging=jar
mvn package
java -cp target/redress-1.0-SNAPSHOT-jar-with-dependencies.jar: redress.Main