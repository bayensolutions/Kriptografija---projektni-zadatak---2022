import java.io.*;

public class User {
    private String username;
    private String password;
    private int numberOfParticipants;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername(){
        return username;
    }

    
    public int getNumberOfParticipants(){
        return numberOfParticipants;
    }

    public void setNumberOfParticipants(int number){
        numberOfParticipants=number;
    }
}
