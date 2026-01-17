import React from "react";
import { useProductsQuery, useSingleProductQuery } from "../query";
import SingleProduct from "./SingleProduct";

function Product() {
  const [page, setPage] = React.useState(1);
  const [limit, setLimit] = React.useState(10);
  const { data, isLoading, isError, refetch, isRefetching } = useProductsQuery(
    page,
    limit,
  );

  const [singleProductId, setSingleProductId] = React.useState(null);

  if (isError) {
    return <div>Error occurred while fetching product data.</div>;
  }

  return (
    <div className="h-screen w-full flex flex-col px-20 py-10 bg-black text-white">
      {singleProductId && (
        <SingleProduct
          id={singleProductId}
          onclose={() => setSingleProductId(null)}
        />
      )}
      <div className="w-6xl mx-auto flex justify-between mb-10">
        <h1 className="text-2xl">Product List</h1>
        <div className="flex gap-2 text-black">
          {page > 1 && (
            <button
              onClick={() => setPage(page - 1)}
              className=" cursor-pointer flex justify-center items-center h-full aspect-square bg-white "
            >
              {page - 1}
            </button>
          )}
          <button className=" cursor-not-allowed flex justify-center items-center h-full aspect-square ring-2 ring-blue-400 bg-white ">
            {page}
          </button>

          {page < Math.ceil(data?.total / limit) && (
            <button
              onClick={() => setPage(page + 1)}
              className=" cursor-pointer flex justify-center items-center h-full aspect-square bg-white "
            >
              {page + 1}
            </button>
          )}
          <h2 className="text-xl text-white">....</h2>
          <h2
            onClick={() => setPage(Math.ceil(data?.total / limit))}
            className="flex justify-center items-center h-full aspect-square bg-white "
          >
            {Math.ceil(data?.total / limit)}
          </h2>
        </div>
        <button
          className="py-1 px-6 rounded-sm cursor-pointer bg-white text-black"
          onClick={() => refetch()}
        >
          Refetch
        </button>
      </div>
      {isLoading || isRefetching ? (
        <div className="h-auto min-h-60 flex justify-center items-center pr-10 w-6xl mx-auto ">
          {isLoading ? "Loading..." : "Refreshing..."}
        </div>
      ) : (
        <ul className="h-auto overflow-scroll overflow-x-hidden pr-10 w-6xl mx-auto grid grid-cols-4  gap-4">
          {data?.products?.map((product) => (
            <div
              onClick={() => setSingleProductId(product.id)}
              key={product.id}
              className="relative border p-4 rounded-lg"
            >
              <h2 className="absolute top-4 left-4 ">{product.id}</h2>
              <img
                src={product.thumbnail}
                alt={product.title}
                className="w-full h-48 object-cover mb-4"
              />
              <div className="flex flex-col gap-0.5">
                <h2 className="text-xl">{product.title}</h2>
                <p className="text-xs">{product.description.slice(20)}</p>
                <p>Price: ${product.price}</p>
              </div>
            </div>
          ))}
        </ul>
      )}
    </div>
  );
}

export default Product;
