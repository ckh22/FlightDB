package flightapp;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.naming.spi.DirStateFactory.Result;

import com.microsoft.sqlserver.jdbc.spatialdatatypes.Point;

/**
 * Runs queries against a back-end database
 */
public class Query {
  // DB Connection
  private Connection conn;
  private String username;
  private String searchResult;

  // Password hashing parameter constants
  private static final int HASH_STRENGTH = 65536;
  private static final int KEY_LENGTH = 128;

  // Canned queries
  private static final String CHECK_FLIGHT_CAPACITY = "SELECT capacity FROM Flights WHERE fid = ?";
  private PreparedStatement checkFlightCapacityStatement;

  // For check dangling
  private static final String TRANCOUNT_SQL = "SELECT @@TRANCOUNT AS tran_count";
  private PreparedStatement tranCountStatement;

  // TODO: YOUR CODE HERE

  public Query() throws SQLException, IOException {
    this(null, null, null, null);
  }

  protected Query(String serverURL, String dbName, String adminName, String password) throws SQLException, IOException {
    conn = serverURL == null ? openConnectionFromDbConn()
        : openConnectionFromCredential(serverURL, dbName, adminName, password);

    prepareStatements();
  }

  /**
   * Return a connecion by using dbconn.properties file
   *
   * @throws SQLException
   * @throws IOException
   */
  public static Connection openConnectionFromDbConn() throws SQLException, IOException {
    // Connect to the database with the provided connection configuration
    Properties configProps = new Properties();
    configProps.load(new FileInputStream("dbconn.properties"));
    String serverURL = configProps.getProperty("flightapp.server_url");
    String dbName = configProps.getProperty("flightapp.database_name");
    String adminName = configProps.getProperty("flightapp.username");
    String password = configProps.getProperty("flightapp.password");
    return openConnectionFromCredential(serverURL, dbName, adminName, password);
  }

  /**
   * Return a connecion by using the provided parameter.
   *
   * @param serverURL example: example.database.widows.net
   * @param dbName    database name
   * @param adminName username to login server
   * @param password  password to login server
   *
   * @throws SQLException
   */
  protected static Connection openConnectionFromCredential(String serverURL, String dbName, String adminName,
      String password) throws SQLException {
    String connectionUrl = String.format("jdbc:sqlserver://%s:1433;databaseName=%s;user=%s;password=%s", serverURL,
        dbName, adminName, password);
    Connection conn = DriverManager.getConnection(connectionUrl);

    // By default, automatically commit after each statement
    conn.setAutoCommit(true);

    // By default, set the transaction isolation level to serializable
    conn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);

    return conn;
  }

  /**
   * Get underlying connection
   */
  public Connection getConnection() {
    return conn;
  }

  /**
   * Closes the application-to-database connection
   */
  public void closeConnection() throws SQLException {
    conn.close();
  }

  /**
   * Clear the data in any custom tables created.
   * 
   * WARNING! Do not drop any tables and do not clear the flights table.
   */
  public void clearTables() {
    try {
      PreparedStatement ps1 = conn.prepareStatement("DELETE FROM Users");
      ps1.executeUpdate();
      ps1.close();
      PreparedStatement ps2 = conn.prepareStatement("DELETE FROM Reservations");
      ps2.executeUpdate();
      ps2.close();
    } catch (SQLException se) {
      se.printStackTrace();
      se.getErrorCode();
    }
  }

  /*
   * prepare all the SQL statements in this method.
   */
  private void prepareStatements() throws SQLException {
    checkFlightCapacityStatement = conn.prepareStatement(CHECK_FLIGHT_CAPACITY);
    tranCountStatement = conn.prepareStatement(TRANCOUNT_SQL);
    // TODO: YOUR CODE HERE
  }

  /**
   * Takes a user's username and password and attempts to log the user in.
   *
   * @param username user's username
   * @param password user's password
   *
   * @return If someone has already logged in, then return "User already logged
   *         in\n" For all other errors, return "Login failed\n". Otherwise,
   *         return "Logged in as [username]\n".
   */
  public String transaction_login(String username, String password) {
    if (this.username != null) {
      return "User already logged in\n";
    }
    try {
      String sql = "SELECT count(*) AS count FROM Users WHERE username = ?";
      PreparedStatement ps = conn.prepareStatement(sql);
      ps.clearParameters();
      ps.setString(1, username.toLowerCase());
      ResultSet rs = ps.executeQuery();
      rs.next();
      int numUser = rs.getInt("count");
      rs.close();
      if (numUser != 0) {
        String sql2 = "SELECT hashVal, saltVal FROM Users WHERE username = ?";
        PreparedStatement ps2 = conn.prepareStatement(sql2);
        ps2.clearParameters();
        ps2.setString(1, username.toLowerCase());
        ResultSet rs2 = ps2.executeQuery();
        rs2.next();
        byte[] result_hash = rs2.getBytes("hashVal");
        byte[] result_salt = rs2.getBytes("saltVal");
        rs2.close();
        KeySpec spec = new PBEKeySpec(password.toCharArray(), result_salt, HASH_STRENGTH, KEY_LENGTH);
        // Generate the hash
        SecretKeyFactory factory = null;
        byte[] hash = null;
        try {
          factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
          hash = factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
          throw new IllegalStateException();
        }
        if (Arrays.equals(hash, result_hash)) {
          this.username = username;
          return "Logged in as " + username + "\n";
        }
      }
      return "Login failed\n";
    } catch (SQLException se) {
      se.printStackTrace();
      se.getErrorCode();
      return "Login failed\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Implement the create user function.
   *
   * @param username   new user's username. User names are unique the system.
   * @param password   new user's password.
   * @param initAmount initial amount to deposit into the user's account, should
   *                   be >= 0 (failure otherwise).
   *
   * @return either "Created user {@code username}\n" or "Failed to create user\n"
   *         if failed.
   */
  public String transaction_createCustomer(String username, String password, int initAmount) {
    SecureRandom random = new SecureRandom();
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);
    SecretKeyFactory factory = null;
    byte[] hash = null;
    try {
      factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      hash = factory.generateSecret(spec).getEncoded();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
      throw new IllegalStateException();
    }
    if (initAmount < 0) {
      return "Failed to create user\n";
    }
    try {
      String sql = "SELECT count(*) AS count FROM Users WHERE username = ?";
      PreparedStatement ps = conn.prepareStatement(sql);
      ps.clearParameters();
      ps.setString(1, username.toLowerCase());
      ResultSet rs = ps.executeQuery();
      rs.next();
      int numUser = rs.getInt("count");
      rs.close();
      if (numUser == 0) {
        String insert = "INSERT INTO Users VALUES (?, ?, ?, ?)";
        PreparedStatement ps2 = conn.prepareStatement(insert);
        ps2.clearParameters();
        ps2.setString(1, username);
        ps2.setBytes(2, hash);
        ps2.setBytes(3, salt);
        ps2.setInt(4, initAmount);
        ps2.executeUpdate();
        return "Created user " + username + "\n";
      }
      return "Failed to create user\n";
    } catch (SQLException se) {
      se.printStackTrace();
      se.getErrorCode();
      return "Failed to create user\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Implement the search function.
   *
   * Searches for flights from the given origin city to the given destination
   * city, on the given day of the month. If {@code directFlight} is true, it only
   * searches for direct flights, otherwise is searches for direct flights and
   * flights with two "hops." Only searches for up to the number of itineraries
   * given by {@code numberOfItineraries}.
   *
   * The results are sorted based on total flight time.
   *
   * @param originCity
   * @param destinationCity
   * @param directFlight        if true, then only search for direct flights,
   *                            otherwise include indirect flights as well
   * @param dayOfMonth
   * @param numberOfItineraries number of itineraries to return
   *
   * @return If no itineraries were found, return "No flights match your
   *         selection\n". If an error occurs, then return "Failed to search\n".
   *
   *         Otherwise, the sorted itineraries printed in the following format:
   *
   *         Itinerary [itinerary number]: [number of flights] flight(s), [total
   *         flight time] minutes\n [first flight in itinerary]\n ... [last flight
   *         in itinerary]\n
   *
   *         Each flight should be printed using the same format as in the
   *         {@code Flight} class. Itinerary numbers in each search should always
   *         start from 0 and increase by 1.
   *
   * @see Flight#toString()
   */
  public String transaction_search(String originCity, String destinationCity, boolean directFlight, int dayOfMonth,
      int numberOfItineraries) {
    try {
      StringBuffer sb = new StringBuffer();
      ArrayList<ArrayList<Flight>> searchResult = new ArrayList<ArrayList<Flight>>();
      try {
        ArrayList<Flight> FlightList = new ArrayList<Flight>();
        String searchDirect = "SELECT TOP (?) F.day_of_month as Day, "
          + "F.carrier_id as Carrier, F.flight_num as Number, F.fid as fid, "
          + "F.origin_city as Origin, F.dest_city as Destination, "
          + "F.actual_time as Duration, F.capacity as Capacity, F.price as Price\n " + "FROM FLIGHTS as F "
          + "WHERE F.origin_city = ? AND F.dest_city = ? AND F.day_of_month = ? " + "AND F.canceled != 1 "
          + "ORDER BY F.actual_time, F.fid ASC";
        String searchIndirect = "SELECT TOP (?) F1.day_of_month as Day1, "
          + "F1.carrier_id as Carrier1, F1.flight_num as Number1, F1.origin_city as Origin1, "
          + "F1.dest_city as Destination1, F1.actual_time as Duration1, F1.capacity as Capacity1, "
          + "F1.price as Price1, F2.day_of_month as Day2, F2.carrier_id as Carrier2, "
          + "F2.flight_num as Number2, F2.origin_city as Origin2, F2.dest_city as Destination2, "
          + "F2.actual_time as Duration2, F2.capacity as Capacity2, F2.price as Price2, "
          + "F1.fid as fid1, F2.fid as fid2, F1.actual_time + F2.actual_time as Total_time "
          + "FROM FLIGHTS as F1, FLIGHTS as F2 "
          + "WHERE F1.origin_city = ? AND F1.dest_city = F2.origin_city AND F2.dest_city = ? "
          + "AND F1.day_of_month = ? AND F2.day_of_month = F1.day_of_month AND F1.canceled != 1 "
          + "AND F2.canceled != 1 " + "ORDER BY Total_time, F1.fid, F2.fid ASC";
        PreparedStatement directStatement = conn.prepareStatement(searchDirect);
        PreparedStatement indirectStatement = conn.prepareStatement(searchIndirect);
        directStatement.clearParameters();
        directStatement.setInt(1, numberOfItineraries);
        directStatement.setString(2, originCity);
        directStatement.setString(3, destinationCity);
        directStatement.setInt(4, dayOfMonth);
        ResultSet results = directStatement.executeQuery();
        while (results.next()) {
          Flight itinerary = helper(results);
          FlightList.add(itinerary);
        }
        results.close();
        if (!directFlight) {
          int size = FlightList.size();
          int index = 0;
          searchResult = new ArrayList<ArrayList<Flight>>();

          indirectStatement.clearParameters();
          indirectStatement.setInt(1, numberOfItineraries);
          indirectStatement.setString(2, originCity);
          indirectStatement.setString(3, destinationCity);
          indirectStatement.setInt(4, dayOfMonth);
          ResultSet result2 = indirectStatement.executeQuery();

          while (result2.next() && (numberOfItineraries - size) > 0) {
            Flight Itinerary1 = new Flight();
            Flight Itinerary2 = new Flight();
            Itinerary1.capacity = result2.getInt("capacity1");
            Itinerary2.capacity = result2.getInt("capacity2");
            Itinerary1.carrierId = result2.getString("Carrier1");
            Itinerary2.carrierId = result2.getString("Carrier2");
            Itinerary1.dayOfMonth = result2.getInt("Day1");
            Itinerary2.dayOfMonth = result2.getInt("Day2");
            Itinerary1.destCity = result2.getString("Destination1");
            Itinerary2.destCity = result2.getString("Destination2");
            Itinerary1.fid = result2.getInt("fid1");
            Itinerary2.fid = result2.getInt("fid2");
            Itinerary1.flightNum = result2.getString("Number1");
            Itinerary2.flightNum = result2.getString("Number2");
            Itinerary1.originCity = result2.getString("Origin1");
            Itinerary2.originCity = result2.getString("Origin2");
            Itinerary1.price = result2.getInt("Price1");
            Itinerary2.price = result2.getInt("Price2");
            Itinerary1.time = result2.getInt("Duration1");
            Itinerary2.time = result2.getInt("Duration2");
            int totalTime = result2.getInt("Total_time");

            while (totalTime >= FlightList.get(0).time && FlightList.size() != 0) {
              sb.append("Itinerary " + index + ": 1 flight(s), " + FlightList.get(0).time + " minutes\n");
              searchResult.add(new ArrayList<Flight>());
              if (FlightList.get(0).capacity != 0) {
                searchResult.get(searchResult.size() - 1).add(FlightList.get(0));
              }
              index++;
              sb.append(FlightList.get(0).toString() + "\n");
              FlightList.remove(0);
            }
            sb.append("Itinerary " + index + ": 2 flight(s), " + totalTime + " minutes\n");
            searchResult.add(new ArrayList<Flight>());
            if (Itinerary1.capacity != 0 && Itinerary2.capacity != 0) {
              searchResult.get(searchResult.size() - 1).add(Itinerary1);
              searchResult.get(searchResult.size() - 1).add(Itinerary2);
            }
            index++;
            sb.append(Itinerary1.toString() + "\n");
            sb.append(Itinerary2.toString() + "\n");
            size++;
          }
          result2.close();
          for (int i = 0; i < FlightList.size(); i++) {
            searchResult.add(new ArrayList<Flight>());
            if (FlightList.get(i).capacity != 0) {
              searchResult.get(searchResult.size() - 1).add(FlightList.get(i));
            }
            sb.append("Itinerary " + index + ": 1 flight(s), " + FlightList.get(i).time + " minutes\n");
            sb.append(FlightList.get(i).toString() + "\n");
            index++;
          }
        } else {
          for (int i = 0; i < FlightList.size(); i++) {
            searchResult.add(new ArrayList<Flight>());
            searchResult.get(searchResult.size() - 1).add(FlightList.get(i));
            sb.append("Itinerary " + i + ": 1 flight(s), " + FlightList.get(i).time + " minutes\n");
            sb.append(FlightList.get(i).toString() + "\n");
          }
        }
        this.searchResult = sb.toString();
        return sb.toString();
      } catch (SQLException se) {
        se.getErrorCode();
        se.getMessage();
        se.printStackTrace();
      }
      this.searchResult = sb.toString();
      return sb.toString();
    } finally {
      checkDanglingTransaction();
    }
  }

  private Flight helper(ResultSet results) {
    Flight F = new Flight();
    try {
      F.capacity = results.getInt("capacity");        // helps find all for indirect flights
      F.carrierId = results.getString("Carrier");
      F.dayOfMonth = results.getInt("Day");
      F.destCity = results.getString("Destination");
      F.fid = results.getInt("fid");
      F.flightNum = results.getString("Number");
      F.originCity = results.getString("Origin");
      F.price = results.getInt("Price");
      F.time = results.getInt("Duration");
    } catch (SQLException e) {
      e.printStackTrace();
    }
    return F;
  }

  /**
   * Implements the book itinerary function.
   *
   * @param itineraryId ID of the itinerary to book. This must be one that is
   *                    returned by search in the current session.
   *
   * @return If the user is not logged in, then return "Cannot book reservations,
   *         not logged in\n". If the user is trying to book an itinerary with an
   *         invalid ID or without having done a search, then return "No such
   *         itinerary {@code itineraryId}\n". If the user already has a
   *         reservation on the same day as the one that they are trying to book
   *         now, then return "You cannot book two flights in the same day\n". For
   *         all other errors, return "Booking failed\n".
   *
   *         And if booking succeeded, return "Booked flight(s), reservation ID:
   *         [reservationId]\n" where reservationId is a unique number in the
   *         reservation system that starts from 1 and increments by 1 each time a
   *         successful reservation is made by any user in the system.
   */


  // PLEASE READ:
  // For the PreparedStatement -> insertCapacity
  // I decided to comment out the Update Query since
  // It will impact the test cases if done +1
  // Storing another column of capacity seemed redundant in reservation
  // So if using an actual Flights database, it will update when booked
  public String transaction_book(int itineraryId) {
    if (searchResult == null) {
      return "No such itinerary " + itineraryId + "\n";
    }
    if (username == null) {
      return "Cannot book reservations, not logged in\n";
    }
    try {
      conn.setAutoCommit(true);
      conn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
      PreparedStatement ps = conn.prepareStatement("SELECT count(*) AS count FROM Reservations");
      PreparedStatement insert = conn.prepareStatement("INSERT INTO Reservations VALUES(?, ?, ?, ?, ?, ?, ?)");
      PreparedStatement searchDate = conn   // finds if the user has already booked a flight on the same day
          .prepareStatement("SELECT count(*) AS count FROM Reservations WHERE username = ? AND day = ? AND cancellationStatus = ?");
//      PreparedStatement insertCapacity = conn.prepareStatement("UPDATE Flights SET capacity = ? WHERE fid = ?");
      searchDate.setString(1, username);        
      searchDate.setString(3, "no");
      conn.setAutoCommit(false);
      ResultSet rs = ps.executeQuery();
      rs.next();
      int reservationID = rs.getInt("count");
      int updated = reservationID + 1;
      rs.close();
      insert.setString(2, username);
      insert.setString(3, "no");
      insert.setString(4, "no");
      insert.setInt(5, reservationID + 1);
      Scanner scr = new Scanner(searchResult);
      String query = "Itinerary " + itineraryId;
      String question1 = "2 flight(s)";
      String question2 = "1 flight(s)";
      while (scr.hasNextLine()) {
        String search = scr.nextLine();
        if (search.contains(query) && search.contains(question2)) {
          String finished = scr.nextLine();
          int fidFrom = finished.indexOf("ID: ");
          String fidMatch = finished.substring(fidFrom + 4, finished.indexOf(" Day:"));
//            insertCapacity.clearParameters();
//            insertCapacity.setInt(2, Integer.parseInt(fidMatch));
          insert.setString(7, fidMatch);
          int priceFrom = finished.indexOf("Price: ");
          String priceMatch = finished.substring(priceFrom + 7);
          int totalCost = Integer.parseInt(priceMatch);
          insert.setInt(1, totalCost);
          int pFromCap = finished.indexOf("Capacity: ");
          String matchCap = finished.substring(pFromCap + 10, finished.indexOf(" Price: "));
          int i = Integer.parseInt(matchCap);
          if (i == 0) {
            return "Booking failed\n"; // finds if capacity is 0
          }
          int dayFrom = finished.indexOf("Day: ");
          String dayMatch = finished.substring(dayFrom + 5, finished.indexOf(" Carrier"));
          int date = Integer.parseInt(dayMatch);
          conn.setAutoCommit(true);
          searchDate.setInt(2, date);
          ResultSet dateResult = searchDate.executeQuery();
          dateResult.next();
          int dateDup = dateResult.getInt("count");
          if (dateDup > 0) {
            return "You cannot book two flights in the same day\n";
          }
          insert.setInt(6, date);
          insert.executeUpdate();
          conn.commit();
          insert.close();
          conn.setAutoCommit(true);
          return "Booked flight(s), reservation ID: " + updated + "\n";
        } else if (search.contains(query) && search.contains(question1)) {
          String finished1 = scr.nextLine();
          String finished2 = scr.nextLine();
          int fidFrom1 = finished1.indexOf("ID: ");
          String fidMatch1 = finished1.substring(fidFrom1 + 4, finished1.indexOf(" Day:"));
          int fidFrom2 = finished2.indexOf("ID: ");
          String fidMatch2 = finished2.substring(fidFrom2 + 4, finished2.indexOf(" Day:"));
          String fidnum = fidMatch1 + "-" + fidMatch2;
          insert.setString(7, fidnum);
          int priceFrom1 = finished1.indexOf("Price: ");
          String priceMatch1 = finished1.substring(priceFrom1 + 7);
          int priceFrom2 = finished2.indexOf("Price: ");
          String priceMatch2 = finished2.substring(priceFrom2 + 7);
          int cost1 = Integer.parseInt(priceMatch1);
          int cost2 = Integer.parseInt(priceMatch2);
          int totalCost = cost1 + cost2;
          insert.setInt(1, totalCost);

          int pFromCap1 = finished1.indexOf("Capacity: ");
          String matchCap1 = finished1.substring(pFromCap1 + 10, finished1.indexOf(" Price: "));
          int pFromCap2 = finished2.indexOf("Capacity: ");
          String matchCap2 = finished2.substring(pFromCap2 + 10, finished2.indexOf(" Price: "));
          int i1 = Integer.parseInt(matchCap1);
          int i2 = Integer.parseInt(matchCap2);
          if (i1 < 1 || i2 < 1) {
            return "Booking failed\n"; // finds if capacity is ok on both flights
          }
          int dayFrom = finished1.indexOf("Day: ");
          String dayMatch = finished1.substring(dayFrom + 5, finished1.indexOf(" Carrier"));
          int date = Integer.parseInt(dayMatch);
          conn.setAutoCommit(true);
          searchDate.setInt(2, date);
          ResultSet dateResult = searchDate.executeQuery();
          dateResult.next();
          int dateDup = dateResult.getInt("count");
          if (dateDup > 0) {
            return "You cannot book two flights in the same day\n";
          }
          insert.setInt(6, date);
          insert.executeUpdate();
          conn.commit();
          insert.close();
          conn.setAutoCommit(true);
          return "Booked flight(s), reservation ID: " + updated + "\n";
        }
      }
      scr.close();
      return "Booking failed\n";
    } catch (SQLException se) {
      se.getErrorCode();
      se.printStackTrace();
      return "Booking failed\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Implements the pay function.
   *
   * @param reservationId the reservation to pay for.
   *
   * @return If no user has logged in, then return "Cannot pay, not logged in\n"
   *         If the reservation is not found / not under the logged in user's
   *         name, then return "Cannot find unpaid reservation [reservationId]
   *         under user: [username]\n" If the user does not have enough money in
   *         their account, then return "User has only [balance] in account but
   *         itinerary costs [cost]\n" For all other errors, return "Failed to pay
   *         for reservation [reservationId]\n"
   *
   *         If successful, return "Paid reservation: [reservationId] remaining
   *         balance: [balance]\n" where [balance] is the remaining balance in the
   *         user's account.
   */
  public String transaction_pay(int reservationId) {
    if (username == null) {
      return "Cannot pay, not logged in\n";
    }
    try {
      String sql = "SELECT cost FROM Reservations WHERE reservationID = ? AND payStatus = ? AND cancellationStatus = ? AND username = ?";
      PreparedStatement ps = conn.prepareStatement(sql);
      ps.setInt(1, reservationId);
      ps.setString(2, "no");
      ps.setString(3, "no");
      ps.setString(4, username);
      conn.setAutoCommit(false);
      ResultSet rs = ps.executeQuery();
      while (rs.next()) {
        int cost = rs.getInt("cost");
        String sql2 = "SELECT * FROM Users WHERE username = ?";
        PreparedStatement ps2 = conn.prepareStatement(sql2);
        ps2.setString(1, this.username);
        ResultSet rs2 = ps2.executeQuery();
        rs2.next();
        int money = rs2.getInt("balance");
        if (money >= cost) {
          int update = money - cost;
          PreparedStatement moneyUpdate = conn.prepareStatement("UPDATE Users SET balance = ? WHERE username = ?");
          moneyUpdate.setInt(1, update);
          moneyUpdate.setString(2, this.username);
          moneyUpdate.executeUpdate();
          PreparedStatement p = conn.prepareStatement("UPDATE Reservations SET payStatus = ? WHERE reservationId = ?");
          p.setString(1, "yes");
          p.setInt(2, reservationId);
          p.executeUpdate();
          conn.setAutoCommit(true);
          return "Paid reservation: " + reservationId + " remaining balance: " + update + "\n";
        } else {
          return "User has only " + money + " in account but itinerary costs " + cost + "\n";
        }
      }
      return "Cannot find unpaid reservation " + reservationId + " under user: " + username + "\n";
    } catch (SQLException se) {
      se.getErrorCode();
      se.getMessage();
      se.printStackTrace();
      return "Failed to pay for reservation " + reservationId + "\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Implements the reservations function.
   *
   * @return If no user has logged in, then return "Cannot view reservations, not
   *         logged in\n" If the user has no reservations, then return "No
   *         reservations found\n" For all other errors, return "Failed to
   *         retrieve reservations\n"
   *
   *         Otherwise return the reservations in the following format:
   *
   *         Reservation [reservation ID] paid: [true or false]:\n [flight 1 under
   *         the reservation]\n [flight 2 under the reservation]\n Reservation
   *         [reservation ID] paid: [true or false]:\n [flight 1 under the
   *         reservation]\n [flight 2 under the reservation]\n ...
   *
   *         Each flight should be printed using the same format as in the
   *         {@code Flight} class.
   *
   * @see Flight#toString()
   */
  public String transaction_reservations() {
    if (this.username == null) {
      return "Cannot view reservations, not logged in\n";
    }
    try {
      StringBuffer sb = new StringBuffer();
      PreparedStatement ps = conn
          .prepareStatement("SELECT * FROM Reservations WHERE username = ? AND cancellationStatus = ?");
      PreparedStatement flights = conn.prepareStatement("SELECT * FROM Flights WHERE fid = ?");
      ps.setString(1, username);
      ps.setString(2, "no");
      ResultSet rs = ps.executeQuery();
      while (rs.next()) {
        String paid = rs.getString("payStatus");
        String fid = rs.getString("fid");
        if (paid.contains("no")) {
          paid = "false";
        } else {
          paid = "true";
        }
        int rid = rs.getInt("reservationId");
        sb.append("Reservation " + rid + " paid: " + paid + ":\n");
        if (fid.contains("-")) {
          String fid1 = fid.substring(0, fid.indexOf("-"));
          String fid2 = fid.substring(fid.indexOf("-") + 1);
          flights.clearParameters();
          flights.setInt(1, Integer.parseInt(fid1));
          ResultSet flightList1 = flights.executeQuery();
          flightList1.next();
          int day1 = flightList1.getInt("day_of_month");
          String carrier1 = flightList1.getString("carrier_id");
          int flightNum1 = flightList1.getInt("flight_num");
          String origin1 = flightList1.getString("origin_city");
          String destination1 = flightList1.getString("dest_city");
          int time1 = flightList1.getInt("actual_time");
          int cap1 = flightList1.getInt("capacity");
          int price1 = flightList1.getInt("price");
          sb.append("ID: " + fid1 + " Day: " + day1 + " Carrier: " + carrier1 + " Number: " + flightNum1 + " Origin: "
              + origin1 + " Dest: " + destination1 + " Duration: " + time1 + " Capacity: " + cap1 + " Price: " + price1
              + "\n");
          flights.clearParameters();
          flights.setInt(1, Integer.parseInt(fid2));
          ResultSet flightList2 = flights.executeQuery();
          flightList2.next();
          int day2 = flightList2.getInt("day_of_month");
          String carrier2 = flightList2.getString("carrier_id");
          int flightNum2 = flightList2.getInt("flight_num");
          String origin2 = flightList2.getString("origin_city");
          String destination2 = flightList2.getString("dest_city");
          int time2 = flightList2.getInt("actual_time");
          int cap2 = flightList2.getInt("capacity");
          int price2 = flightList2.getInt("price");
          sb.append("ID: " + fid2 + " Day: " + day2 + " Carrier: " + carrier2 + " Number: " + flightNum2 + " Origin: "
              + origin2 + " Dest: " + destination2 + " Duration: " + time2 + " Capacity: " + cap2 + " Price: " + price2
              + "\n");
        } else {
          flights.clearParameters();
          flights.setInt(1, Integer.parseInt(fid));
          ResultSet flightList = flights.executeQuery();
          flightList.next();
          int day = flightList.getInt("day_of_month");
          String carrier = flightList.getString("carrier_id");
          int flightNum = flightList.getInt("flight_num");
          String origin = flightList.getString("origin_city");
          String destination = flightList.getString("dest_city");
          int time = flightList.getInt("actual_time");
          int cap = flightList.getInt("capacity");
          int price = flightList.getInt("price");
          sb.append(
              "ID: " + fid + " Day: " + day + " Carrier: " + carrier + " Number: " + flightNum + " Origin: " + origin
                  + " Dest: " + destination + " Duration: " + time + " Capacity: " + cap + " Price: " + price + "\n");
        }
      }
      if (sb.length() == 0) {
        return "Failed to retrieve reservations\n";
      } else {
        return sb.toString();
      }
    } catch (SQLException se) {
      se.getErrorCode();
      se.getMessage();
      se.printStackTrace();
      return "Failed to retrieve reservations\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Implements the cancel operation.
   *
   * @param reservationId the reservation ID to cancel
   *
   * @return If no user has logged in, then return "Cannot cancel reservations,
   *         not logged in\n" For all other errors, return "Failed to cancel
   *         reservation [reservationId]\n"
   *
   *         If successful, return "Canceled reservation [reservationId]\n"
   *
   *         Even though a reservation has been canceled, its ID should not be
   *         reused by the system.
   */
  public String transaction_cancel(int reservationId) {
    if (username == null) {
      return "Cannot cancel reservations, not logged in\n";
    }
    try {
      PreparedStatement ps = conn.prepareStatement(
          "SELECT * FROM Reservations WHERE reservationID = ? AND username = ? AND cancellationStatus = ?");
      PreparedStatement delete = conn
          .prepareStatement("UPDATE Reservations SET cancellationStatus = ? WHERE reservationID = ?");
      ps.setInt(1, reservationId);
      ps.setString(2, username);
      ps.setString(3, "no");
      delete.setString(1, "yes");
      delete.setInt(2, reservationId);
      conn.setAutoCommit(false);
      ResultSet rs = ps.executeQuery();
      if (rs.next()) {
        delete.executeUpdate();
        conn.setAutoCommit(true);
        delete.close();
        return "Canceled reservation " + reservationId + "\n";
      }
      return "Failed to cancel reservation " + reservationId + "\n";
    } catch (SQLException se) {
      se.getErrorCode();
      se.getMessage();
      se.printStackTrace();
      return "Failed to cancel reservation " + reservationId + "\n";
    } finally {
      checkDanglingTransaction();
    }
  }

  /**
   * Example utility function that uses prepared statements
   */
  private int checkFlightCapacity(int fid) throws SQLException {
    checkFlightCapacityStatement.clearParameters();
    checkFlightCapacityStatement.setInt(1, fid);
    ResultSet results = checkFlightCapacityStatement.executeQuery();
    results.next();
    int capacity = results.getInt("capacity");
    results.close();

    return capacity;
  }

  /**
   * Throw IllegalStateException if transaction not completely complete, rollback.
   * 
   */
  private void checkDanglingTransaction() {
    try {
      try (ResultSet rs = tranCountStatement.executeQuery()) {
        rs.next();
        int count = rs.getInt("tran_count");
        if (count > 0) {
          throw new IllegalStateException(
              "Transaction not fully commit/rollback. Number of transaction in process: " + count);
        }
      } finally {
        conn.setAutoCommit(true);
      }
    } catch (SQLException e) {
      throw new IllegalStateException("Database error", e);
    }
  }

  private static boolean isDeadLock(SQLException ex) {
    return ex.getErrorCode() == 1205;
  }

  /**
   * A class to store flight information.
   */
  class Flight {
    public int fid;
    public int dayOfMonth;
    public String carrierId;
    public String flightNum;
    public String originCity;
    public String destCity;
    public int time;
    public int capacity;
    public int price;

    @Override
    public String toString() {
      return "ID: " + fid + " Day: " + dayOfMonth + " Carrier: " + carrierId + " Number: " + flightNum + " Origin: "
          + originCity + " Dest: " + destCity + " Duration: " + time + " Capacity: " + capacity + " Price: " + price;
    }
  }
}
