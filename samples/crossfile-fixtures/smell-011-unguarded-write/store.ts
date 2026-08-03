export interface Note {
  id: string;
  ownerId: string;
  body: string;
  sharedWith: string[];
}

const notes: Note[] = [];

export async function addNote(note: Note): Promise<Note> {
  notes.push(note);
  return note;
}

export async function editNote(id: string, body: string): Promise<Note | undefined> {
  const found = notes.find((n) => n.id === id);
  if (found) {
    found.body = body;
  }
  return found;
}

export async function dropNote(id: string): Promise<void> {
  const kept = notes.filter((n) => n.id !== id);
  notes.length = 0;
  notes.push(...kept);
}

export async function addShare(id: string, recipient: string): Promise<Note | undefined> {
  const found = notes.find((n) => n.id === id);
  if (found) {
    found.sharedWith.push(recipient);
  }
  return found;
}
