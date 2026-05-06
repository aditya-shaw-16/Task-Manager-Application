import { createSlice } from "@reduxjs/toolkit";

const getStoredTheme = () => {
  if (typeof window === "undefined") {
    return "system";
  }

  return localStorage.getItem("theme") || "system";
};

const initialState = {
  theme: getStoredTheme(),
};

const themeSlice = createSlice({
  name: "theme",
  initialState,
  reducers: {
    setTheme: (state, action) => {
      state.theme = action.payload;
      localStorage.setItem("theme", action.payload);
    },
  },
});

export const { setTheme } = themeSlice.actions;

export default themeSlice.reducer;