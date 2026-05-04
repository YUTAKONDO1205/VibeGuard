function render(userInput) {
  const el = document.getElementById("out");
  // AI-prone: assigning untrusted data to innerHTML
  el.innerHTML = userInput;
}

function eval_user(input) {
  // AI-prone: eval() of user input
  return eval(input);
}

function token() {
  // AI-prone: weak randomness for security context
  const sessionId = Math.random().toString(36).slice(2);
  return sessionId;
}
