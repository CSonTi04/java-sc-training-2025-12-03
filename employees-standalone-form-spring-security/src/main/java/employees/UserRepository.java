package employees;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    //itt is fel lehet használni a SPEL-t és a security-s dolgokat - spring data jpa integráció, így lehet spórolni a lekérdezésekkel
    //@Query("select distinct u from User u left join fetch u.authorities where u.username = :username and e.user =?#{authentication.name}}")
    @Query("select distinct u from User u left join fetch u.authorities where u.username = :username")
    Optional<User> findUserByUsername(String username);
}
