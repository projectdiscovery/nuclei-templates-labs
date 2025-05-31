/*
 * WARNING: This application contains serious security vulnerabilities. Run it at your own risk! 
 * It is recommended using a backed-up and sheltered environment (such as a VM with a recent snapshot 
 * and host-only networking). Do not upload this application to any Internet facing servers, 
 * as they will be compromised.
 * 
 * DISCLAIMER: I do not take responsibility for the way in which any one uses this application 
 * (SpringBreakVulnerableApplication). The only purpose of this application is to be a test scenario 
 * for the Spring Break exploit and it should not be used maliciously. If your server is compromised via 
 * an installation of SpringBreakVulnerableApplication it is not my responsibility, it is the responsibility 
 * of the person(s) who uploaded and installed it.
 * 
 */

package com.afs.vulnerable.springbreak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringDataRestApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringDataRestApplication.class, args);
    }
}
