export const formatDate = (date) => {
    // Get the month, day, and year
    const month = date.toLocaleString("en-US", { month: "short" });
    const day = date.getDate();
    const year = date.getFullYear();
  
    const formattedDate = `${day}-${month}-${year}`;
  
    return formattedDate;
  };
  
  export function dateFormatter(dateString) {
    const inputDate = new Date(dateString);
  
    if (isNaN(inputDate)) {
      return "Invalid Date";
    }
  
    const year = inputDate.getFullYear();
    const month = String(inputDate.getMonth() + 1).padStart(2, "0");
    const day = String(inputDate.getDate()).padStart(2, "0");
  
    const formattedDate = `${year}-${month}-${day}`;
    return formattedDate;
  }
  
  export function getInitials(fullName) {
      if (!fullName || typeof fullName !== "string") {
        return "U";
      }

      const names = fullName.trim().split(/\s+/).filter(Boolean);

      if (names.length === 0) {
        return "U";
      }

      const initials = names.slice(0, 2).map((name) => name[0].toUpperCase());

      const initialsStr = initials.join("");

      return initialsStr || "U";
  }

export const applyThemePreference = (themePreference) => {
  if (typeof document === "undefined") {
    return;
  }

  const systemPrefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const shouldUseDark =
    themePreference === "dark" ||
    (themePreference === "system" && systemPrefersDark);

  document.documentElement.classList.toggle("dark", shouldUseDark);
  document.body.classList.toggle("dark", shouldUseDark);
  document.documentElement.dataset.theme = shouldUseDark ? "dark" : "light";
  document.documentElement.style.colorScheme = shouldUseDark ? "dark" : "light";
};

export const getResolvedTheme = (themePreference) => {
  if (themePreference === "dark") {
    return "dark";
  }

  if (themePreference === "light") {
    return "light";
  }

  if (typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches) {
    return "dark";
  }

  return "light";
};
  
  export const PRIOTITYSTYELS = {
    high: "text-red-600",
    medium: "text-yellow-600",
    low: "text-blue-600",
  };
  
  export const TASK_TYPE = {
    todo: "bg-blue-600",
    "in progress": "bg-yellow-600",
    completed: "bg-green-600",
  };
  
  export const BGS = [
    "bg-blue-600",
    "bg-yellow-600",
    "bg-red-600",
    "bg-green-600",
  ];