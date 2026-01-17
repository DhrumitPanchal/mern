import { useQuery } from "@tanstack/react-query";
import axios from "axios";

const fetchProduct = async (page, limit) => {
  try {
    console.log((page - 1) * limit);
    const response = await axios.get(
      `https://dummyjson.com/products?limit=${limit}&skip=${(page - 1) * limit}`,
    );
    return response.data;
  } catch (error) {
    console.log(error);
    throw new Error("Failed to fetch product data");
  }
};

const fetchSingleProduct = async (id) => {
  try {
    const response = await axios.get("https://dummyjson.com/products/" + id);
    return response.data;
  } catch (error) {
    throw new Error("Failed to fetch product data");
  }
};

export const useProductsQuery = (page, limit) => {
  return useQuery({
    queryKey: ["products", "all", page, limit],
    queryFn: () => fetchProduct(page, limit),
  });
};

export const useSingleProductQuery = (id) => {
  return useQuery({
    queryKey: ["product", "one", id],
    queryFn: () => fetchSingleProduct(id),
    enabled: !!id,
  });
};
