package org.sid.authservice.security.service;

import org.sid.authservice.security.entities.AppRole;
import org.sid.authservice.security.entities.AppUser;

import java.util.List;

public interface AccountService {
    public AppUser addNewUser(AppUser user);
    public AppRole addNewRole(AppRole role);
    public void addRoleToUser(String username, String roleName);
    public AppUser loadUserByUsername(String username);
    public List<AppUser> listUsers();
}
