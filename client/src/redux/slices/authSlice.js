import { createSlice } from "@reduxjs/toolkit";

const initialState = {
  user: localStorage.getItem("userInfo")
    ? (() => {
        const storedUser = JSON.parse(localStorage.getItem("userInfo"));
        if (!storedUser) {
          return null;
        }

        const { profilePic, ...sanitizedUser } = storedUser;
        return sanitizedUser;
      })()
    : null,

  isSidebarOpen: false,
};

const authSlice = createSlice({
  name: "auth",
  initialState,
  reducers: {
    setCredentials: (state, action) => {
      const { profilePic, ...sanitizedUser } = action.payload || {};
      state.user = sanitizedUser;
      localStorage.setItem("userInfo", JSON.stringify(sanitizedUser));
    },
    logout: (state, action) => {
      state.user = null;
      localStorage.removeItem("userInfo");
    },
    setOpenSidebar: (state, action) => {
      state.isSidebarOpen = action.payload;
    },
  },
});

export const { setCredentials, logout, setOpenSidebar } = authSlice.actions;

export default authSlice.reducer;