package com.example.springbootrolebasedauthorization.security;

//import jakarta.persistence.*;
//import lombok.*;
//
//import java.io.Serializable;
//import java.util.HashSet;
//import java.util.Set;
//
//@Entity
//@Table(name = "users")
//@AllArgsConstructor
//@NoArgsConstructor
//@Getter
//@Setter
//public class User implements Serializable {
//
//    @Id
//    @GeneratedValue(strategy = GenerationType.IDENTITY)
//    private Long id;
//    @Column(nullable = false, unique = true)
//    private String username;
//
//    @Column(nullable = false)
//    private String password;
//
//    @ManyToMany(fetch = FetchType.EAGER)
//    private Set<Role> roles = new HashSet<>();
//
//    private boolean enabled;
//}


//import jakarta.persistence.*;
//import jakarta.persistence.*;
import lombok.*;

import javax.persistence.*;
//import javax.persistence.Entity;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class User implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    private boolean enabled;
}
