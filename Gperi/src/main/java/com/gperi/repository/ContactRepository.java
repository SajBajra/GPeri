package com.gperi.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.gperi.model.Contact;

public interface ContactRepository extends JpaRepository<Contact, Integer>{

}
