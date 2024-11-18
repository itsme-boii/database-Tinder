# Tinder App Database Setup  

This file provides instructions for setting up the database required for the Tinder-like app. The database is managed using **MySQL**, and the schema is initialized by running `database.js`.

---

## Prerequisites  

1. **MySQL Server**: Ensure MySQL is installed and running on your system.  
2. **Node.js**: Required to execute the `database.js` script.  
3. **MySQL Client**: Access to a MySQL client (CLI or GUI) for database management.  

---

## Database Schema  

The database consists of the following tables:  

### 1. `users`  
Stores user profile data.  
- **Columns**:  
  - `id` (INT, Primary Key, Auto Increment)  
  - `name` (VARCHAR)  
  - `email` (VARCHAR, Unique)  
  - `password` (VARCHAR)  
  - `profile_image_url` (TEXT)  
  - `created_at` (TIMESTAMP)  

### 2. `swipes`  
Tracks swipe actions between users.  
- **Columns**:  
  - `id` (INT, Primary Key, Auto Increment)  
  - `swiper_id` (INT, Foreign Key referencing `users.id`)  
  - `swiped_id` (INT, Foreign Key referencing `users.id`)  
  - `is_like` (BOOLEAN)  
  - `created_at` (TIMESTAMP)  

### 3. `matches`  
Stores mutual matches between users.  
- **Columns**:  
  - `id` (INT, Primary Key, Auto Increment)  
  - `user1_id` (INT, Foreign Key referencing `users.id`)  
  - `user2_id` (INT, Foreign Key referencing `users.id`)  
  - `created_at` (TIMESTAMP)  

### 4. `messages`  
Stores chat messages exchanged between matched users.  
- **Columns**:  
  - `id` (INT, Primary Key, Auto Increment)  
  - `match_id` (INT, Foreign Key referencing `matches.id`)  
  - `sender_id` (INT, Foreign Key referencing `users.id`)  
  - `message` (TEXT)  
  - `timestamp` (TIMESTAMP)  

---

