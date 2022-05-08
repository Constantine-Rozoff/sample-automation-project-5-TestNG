package net.absoft.db;

import java.util.Map;

public class DbConnection {
    private static DbConnection self;

    public DbConnection() {
        //Should set up connection to DB server
    }

    public static DbConnection getInstance() {
        if(self == null) {
            self = new DbConnection();
        }
        return self;
    }

    public boolean authenticate(String email, String password) {
        //Mimic request to DB server
        Map<String, String> users = Map.of(
                "user1@test.com, password1",
                "user2@test.com, password2"
        );
        return users.containsKey(email) && users.get(email).contentEquals(password);
    }
}
