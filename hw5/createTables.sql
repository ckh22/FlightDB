CREATE TABLE Users (
    username VARCHAR(20) PRIMARY KEY,
    hashVal VARBINARY(16),
    saltVal VARBINARY(16),
    balance INTEGER
);
CREATE TABLE Reservations (
    cost INTEGER,
    username VARCHAR(20),
    payStatus VARCHAR(3),
    cancellationStatus VARCHAR(3),
    reservationID INTEGER PRIMARY KEY,
    day INTEGER,
    fid VARCHAR(20)
);
