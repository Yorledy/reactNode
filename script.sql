CREATE DATABASE proyecto_sena_final;

USE proyecto_sena_final;

CREATE TABLE usuario (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(50),
    apellido VARCHAR(50),
    email VARCHAR(100) UNIQUE,
    password VARCHAR(255)
);


INSERT INTO usuario (nombre, apellido, email, password) 
VALUES ('Juan', 'Perez', 'juan@example.com', 'contraseña_encriptada');
