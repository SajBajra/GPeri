package com.gperi.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.gperi.model.Contact;
import com.gperi.repository.ContactRepository;

@Service
public class ContactService {

	@Autowired
	ContactRepository contactRepository;
	
	public Contact saveContact(Contact contact) {
        return contactRepository.save(contact);
    }
	public List<Contact> getAllContact() {
        return contactRepository.findAll();
    }
}
