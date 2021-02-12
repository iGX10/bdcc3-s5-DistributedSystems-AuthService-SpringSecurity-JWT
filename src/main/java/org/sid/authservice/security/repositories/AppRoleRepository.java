package org.sid.authservice.security.repositories;

import org.sid.authservice.security.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole, Long> {
    public AppRole findByName(String roleName);
}
