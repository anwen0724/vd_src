module auth_ctrl (
    input  logic clk_i,
    input  logic rst_ni,
    input  logic debug_mode_i,
    output logic auth_valid_o
);

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            auth_valid_o <= 1'b0;
        end else if (debug_mode_i) begin
            auth_valid_o <= 1'b1;
        end
    end

endmodule

