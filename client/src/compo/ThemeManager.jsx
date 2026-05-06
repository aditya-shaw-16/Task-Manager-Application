import { useLayoutEffect } from "react";
import { useSelector } from "react-redux";
import { applyThemePreference } from "../Utils";

const ThemeManager = () => {
  const { theme } = useSelector((state) => state.theme);

  useLayoutEffect(() => {
    applyThemePreference(theme);

    if (theme !== "system") {
      return undefined;
    }

    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    const handleChange = () => applyThemePreference("system");

    mediaQuery.addEventListener("change", handleChange);

    return () => mediaQuery.removeEventListener("change", handleChange);
  }, [theme]);

  return null;
};

export default ThemeManager;