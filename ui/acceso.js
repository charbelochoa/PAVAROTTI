"use strict";

document.getElementById("sign-in").onsubmit = async (event) => {
  event.preventDefault();
  const button = event.submitter;
  const message = document.getElementById("access-error");
  const credentials = Object.fromEntries(new FormData(event.currentTarget));
  button.disabled = true;
  message.textContent = "";
  try {
    const response = await fetch("/api/acceso/ingresar", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(credentials)
    });
    if (!response.ok) throw new Error((await response.text()).trim());
    window.location.replace("/");
  } catch (error) {
    message.textContent = error.message;
    button.disabled = false;
  }
};
