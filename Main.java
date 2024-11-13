/*
 * Author: Russell Sullivan
 * Date First Modified: 7/10/2024
 * Description: Most vulnerabilities within a network is going to be associated with certain port numbers.
 *      This program's purpose is to scan and print data for each port on the system. 
 * 
 *      -TODO:If sus activity is going on, it will pause
 *          the malware and ask the user what to do with it.
 * 
 */

import java.net.*;

public class Main {

    // isPortInUse
    // recieves: a port number
    // returns: -true if port is in use
    //          -false if port is available
    public static boolean isPortInUse(int port) {
        try (Socket ignored = new Socket("localhost", port)) {
            return true;  // The port is in use
        } catch (java.io.IOException ignored) {
            return false;  // The port is available
        }
    }
    public static void main(String[] args) {
        for (int port = 1; port <= 1024; port++) {
            if (isPortInUse(port)) {
                System.out.println("Port " + port + " is in use!");
            } else {
                System.out.println("Port " + port + " is available.");
            }
        }
    }
}