package com.secure.notes.controllers;

import com.secure.notes.models.Note;
import com.secure.notes.services.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/notes")
public class NoteController {
    @Autowired
    private NoteService noteService;

    // AuthenticationPrincipal gets currently authenticated user
    @PostMapping
    public Note createNote(@RequestBody Note note, @AuthenticationPrincipal UserDetails userDetails){
        String username = userDetails.getUsername(); // gets username from active User
        System.out.println("User Details: " + username);
        return noteService.createNoteForUser(username, note.getContent());
    }

    @GetMapping
    public List<Note> getUserNotes(@AuthenticationPrincipal UserDetails userDetails){
        System.out.println("getting user notes");
        return noteService.getNotesForUser(userDetails.getUsername());
    }

    @PutMapping("/{noteId}")
    public Note updateNote(@PathVariable Long noteId, @RequestBody String content, @AuthenticationPrincipal UserDetails userDetails){
        return noteService.updateNoteForUser(noteId, content, userDetails.getUsername());
    }

    @DeleteMapping("/{noteId}")
    public void deleteNote(@PathVariable Long noteId, @AuthenticationPrincipal UserDetails userDetails){
        noteService.deleteNoteForUser(noteId, userDetails.getUsername());
    }
}
