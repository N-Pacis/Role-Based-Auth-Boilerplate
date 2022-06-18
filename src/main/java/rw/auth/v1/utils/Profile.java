package rw.auth.v1.utils;

import lombok.AllArgsConstructor;
import lombok.Data;
import rw.auth.v1.enums.ERole;
import rw.auth.v1.exceptions.BadRequestException;
import rw.auth.v1.models.User;

@Data
@AllArgsConstructor
public class Profile {
    Object profile;

    public User asUser() {
        return (User) profile;
    }

    private void is(ERole role) {
        User user = (User) profile;
        if (user.getRole() != role)
            throw new BadRequestException("You must be a " + role.toString() + " to use this resource ...");
    }

}
