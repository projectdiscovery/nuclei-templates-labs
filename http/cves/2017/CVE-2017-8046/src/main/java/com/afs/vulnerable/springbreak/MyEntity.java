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

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class MyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    private String name;

    private String attribute;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAttribute() {
        return attribute;
    }

    public void setAttribute(String attribute) {
        this.attribute = attribute;
    }

}
