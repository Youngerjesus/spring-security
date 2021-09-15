package com.example.springbootbasicsecuritydemo.account;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AccountService implements UserDetailsService {

    private final AccountRepository accountRepository;

    public AccountService(AccountRepository accountRepository) {
        this.accountRepository = accountRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Account> account = accountRepository.findByUsername(username);

        account.orElseThrow(() -> { throw new UsernameNotFoundException(username); });

        return User.builder()
                .username(account.get().getUsername())
                .password(account.get().getPassword())
                .roles(account.get().getRole())
                .build();
    }
}
