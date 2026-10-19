(() => {
  const sidebar = document.getElementById("sidebar");
  const backdrop = document.getElementById("backdrop");
  const menuButton = document.getElementById("menu-button");
  const search = document.getElementById("doc-search");
  const links = Array.from(document.querySelectorAll(".nav-link"));
  const sections = links.map((link) => document.querySelector(link.getAttribute("href"))).filter(Boolean);
  const closeMenu = () => {
    sidebar.classList.remove("open");
    backdrop.classList.remove("show");
    menuButton.setAttribute("aria-expanded", "false");
  };
  menuButton.addEventListener("click", () => {
    const open = sidebar.classList.toggle("open");
    backdrop.classList.toggle("show", open);
    menuButton.setAttribute("aria-expanded", String(open));
  });
  backdrop.addEventListener("click", closeMenu);
  links.forEach((link) => link.addEventListener("click", closeMenu));
  document.querySelectorAll(".copy").forEach((button) => {
    button.addEventListener("click", async () => {
      const code = button.closest(".code").querySelector("pre").innerText;
      try {
        await navigator.clipboard.writeText(code);
        button.textContent = "Copied";
      } catch {
        button.textContent = "Select code";
      }
      window.setTimeout(() => { button.textContent = "Copy"; }, 1400);
    });
  });
  search.addEventListener("input", () => {
    const query = search.value.trim().toLowerCase();
    links.forEach((link) => {
      const section = document.querySelector(link.getAttribute("href"));
      const matches = !query || (section && section.innerText.toLowerCase().includes(query));
      link.hidden = !matches;
      if (section) section.hidden = Boolean(query) && !matches;
    });
  });
  search.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      search.value = "";
      search.dispatchEvent(new Event("input"));
      search.blur();
    }
    if (event.key === "Enter") {
      const first = links.find((link) => !link.hidden);
      if (first) document.querySelector(first.getAttribute("href")).scrollIntoView({ behavior: "smooth" });
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
      event.preventDefault();
      search.focus();
    }
  });
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        links.forEach((link) => link.classList.toggle("active", link.hash === "#" + entry.target.id));
      });
    }, { rootMargin: "-20% 0px -72% 0px" });
    sections.forEach((section) => observer.observe(section));
  }
})();
