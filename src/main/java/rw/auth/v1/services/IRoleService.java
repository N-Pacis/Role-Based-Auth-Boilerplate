package rw.auth.v1.services;

import rw.auth.v1.enums.ERole;
import rw.auth.v1.models.Role;

import java.util.Set;

public interface IRoleService {

    Role findByName(ERole role);

    Set<Role> getRoleInaHashSet(ERole role);
}
