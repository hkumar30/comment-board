-- Up

CREATE TABLE Messages(
    id INTEGER PRIMARY KEY,
    message STRING,
    authorId INTEGER,
    FOREIGN KEY (authorID) REFERENCES Users(id)
);

CREATE TABLE Users(
    id INTEGER PRIMARY KEY,
    username STRING UNIQUE,
    passwordHash STRING
);

CREATE TABLE AuthTokens (
    token STRING PRIMARY KEY,
    userId INTEGER,
    FOREIGN KEY (userId) REFERENCES Users(id)
);

-- Down

DROP TABLE Messages;
DROP TABLE Users;
DROP Table AuthTokens;