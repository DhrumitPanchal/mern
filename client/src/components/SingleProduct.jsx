import React from "react";
import { useSingleProductQuery } from "../query";

function SingleProduct({ id, onclose }) {
  const { data, isLoading, isError } = useSingleProductQuery(id);
  return (
    <div className="h-screen w-full flex items-center bg-white/10 backdrop-blur-sm absolute top-0 left-0 z-20">
      <div className="relative p-10 rounded-lg w-6xl mx-auto h-fit flex gap-20 bg-black">
        <div
          onClick={onclose}
          className="cursor-pointer absolute -top-10 -right-10 h-10 w-10 font-extrabold"
        >
          X
        </div>
        <img className="h-80 aspect-square" src={data?.thumbnail} />

        <div className="text-white flex flex-col gap-2">
          <h1 className="text-2xl">{data?.title}</h1>
          <p>{data?.description}</p>
          <p>Price: ${data?.price}</p>
        </div>
      </div>
    </div>
  );
}

export default SingleProduct;
