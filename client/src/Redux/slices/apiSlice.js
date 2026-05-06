import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";

const API_URI = import.meta.env.VITE_API_URL || "http://localhost:8800/api";

const baseQuery = fetchBaseQuery({
  baseUrl: API_URI,
  credentials: "include",
});

export const apiSlice = createApi({
  baseQuery,
  tagTypes: ["Dashboard", "Task", "User"],
  endpoints: (builder) => ({
    getDashboard: builder.query({
      query: () => "/task/dashboard",
      providesTags: ["Dashboard"],
    }),
    getTasks: builder.query({
      query: ({ stage, isTrashed } = {}) => ({
        url: "/task",
        params: {
          ...(stage ? { stage } : {}),
          ...(typeof isTrashed === "boolean" ? { isTrashed } : {}),
        },
      }),
      providesTags: ["Task"],
    }),
    getTaskById: builder.query({
      query: (id) => `/task/${id}`,
      providesTags: ["Task"],
    }),
    createTask: builder.mutation({
      query: (body) => ({
        url: "/task/create",
        method: "POST",
        body,
      }),
      invalidatesTags: ["Task", "Dashboard"],
    }),
    updateTask: builder.mutation({
      query: ({ id, ...body }) => ({
        url: `/task/update/${id}`,
        method: "PUT",
        body,
      }),
      invalidatesTags: ["Task", "Dashboard"],
    }),
    getUsers: builder.query({
      query: () => "/user/get-team",
      providesTags: ["User"],
    }),
    registerUser: builder.mutation({
      query: (body) => ({
        url: "/user/register",
        method: "POST",
        body,
      }),
      invalidatesTags: ["User", "Dashboard"],
    }),
    loginUser: builder.mutation({
      query: (body) => ({
        url: "/user/login",
        method: "POST",
        body,
      }),
    }),
    updateUserProfile: builder.mutation({
      query: (body) => ({
        url: "/user/profile",
        method: "PUT",
        body,
      }),
      invalidatesTags: ["User", "Dashboard"],
    }),
    changePassword: builder.mutation({
      query: (body) => ({
        url: "/user/change-password",
        method: "PUT",
        body,
      }),
      invalidatesTags: ["User"],
    }),
    logout: builder.mutation({
      query: () => ({
        url: "/user/logout",
        method: "POST",
      }),
    }),
  }),
});

export const {
  useGetDashboardQuery,
  useGetTasksQuery,
  useGetTaskByIdQuery,
  useCreateTaskMutation,
  useUpdateTaskMutation,
  useGetUsersQuery,
  useRegisterUserMutation,
  useLoginUserMutation,
  useUpdateUserProfileMutation,
  useChangePasswordMutation,
  useLogoutMutation,
} = apiSlice;