import {configureStore} from "@reduxjs/toolkit";
import authReducer from "./slices/authSlice.js";
import themeReducer from "./slices/themeSlice.js";
import {apiSlice} from "./slices/apiSlice.js";

const store = configureStore({
    reducer: {
        [apiSlice.reducerPath]: apiSlice.reducer,
        auth: authReducer,
        theme: themeReducer,
    },
    middleware: (getDefaultMiddleware) => 
        getDefaultMiddleware().concat(apiSlice.middleware),
    devTools: true,
});

export default store;
