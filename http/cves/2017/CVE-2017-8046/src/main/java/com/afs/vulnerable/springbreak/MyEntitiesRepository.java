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

import java.util.List;

import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

@RepositoryRestResource(collectionResourceRel = "entity", path = "entity")
public interface MyEntitiesRepository extends PagingAndSortingRepository<MyEntity, Long> {
    List<MyEntity> findByName(@Param("name") String name);
}
